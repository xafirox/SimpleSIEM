package sieg

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
)

// frameWriter chunks a stream into AEAD-or-plain frames so a backup
// of arbitrary size streams to disk without the encrypter or any
// downstream consumer holding the whole payload in memory. When aead
// is nil the writer just length-prefixes plaintext chunks; the wire
// format is the same in either case so the reader doesn't need a
// separate code path beyond skipping decryption.
//
// Frame layout (matches frameReader):
//
//	[ 4B big-endian length | top bit = final flag ]
//	[ length bytes payload (ciphertext+tag, or plaintext) ]
type frameWriter struct {
	w         io.Writer
	aead      cipher.AEAD
	nonceBase [backupNonceBas]byte
	counter   uint64
	buf       []byte
	closed    bool
}

const finalFrameBit uint32 = 1 << 31

func newFrameWriter(w io.Writer, aead cipher.AEAD, nonceBase [backupNonceBas]byte) *frameWriter {
	return &frameWriter{
		w:         w,
		aead:      aead,
		nonceBase: nonceBase,
		buf:       make([]byte, 0, backupChunkSize),
	}
}

func (f *frameWriter) Write(p []byte) (int, error) {
	if f.closed {
		return 0, fmt.Errorf("frameWriter: write after close")
	}
	written := 0
	for len(p) > 0 {
		space := backupChunkSize - len(f.buf)
		take := len(p)
		if take > space {
			take = space
		}
		f.buf = append(f.buf, p[:take]...)
		p = p[take:]
		written += take
		if len(f.buf) == backupChunkSize {
			if err := f.flushFrame(false); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// Close flushes the trailing buffer as the final frame. Safe to call
// once; a second call is a no-op so defer chains stay simple.
func (f *frameWriter) Close() error {
	if f.closed {
		return nil
	}
	f.closed = true
	return f.flushFrame(true)
}

func (f *frameWriter) flushFrame(final bool) error {
	payload := f.buf
	if f.aead != nil {
		nonce := makeFrameNonce(f.nonceBase, f.counter)
		payload = f.aead.Seal(nil, nonce, f.buf, nil)
	}
	hdr := uint32(len(payload))
	if final {
		hdr |= finalFrameBit
	}
	var hdrBuf [4]byte
	binary.BigEndian.PutUint32(hdrBuf[:], hdr)
	if _, err := f.w.Write(hdrBuf[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := f.w.Write(payload); err != nil {
			return err
		}
	}
	f.counter++
	f.buf = f.buf[:0]
	return nil
}

// frameReader is the inverse of frameWriter. Reads frame-by-frame,
// decrypts (when aead non-nil), and exposes the concatenated payload
// via io.Reader so the consumer can pipe it through gzip/tar
// transparently. Truncation detection: EOF before a final-flagged
// frame returns errBackupTruncated.
type frameReader struct {
	r         io.Reader
	aead      cipher.AEAD
	nonceBase [backupNonceBas]byte
	counter   uint64
	buf       []byte
	cursor    int
	doneFinal bool
	hitEOF    bool
}

func newFrameReader(r io.Reader, aead cipher.AEAD, nonceBase [backupNonceBas]byte) *frameReader {
	return &frameReader{r: r, aead: aead, nonceBase: nonceBase}
}

func (f *frameReader) Read(p []byte) (int, error) {
	if f.cursor >= len(f.buf) {
		if f.doneFinal {
			return 0, io.EOF
		}
		if f.hitEOF {
			return 0, errBackupTruncated
		}
		if err := f.fillNextFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, f.buf[f.cursor:])
	f.cursor += n
	return n, nil
}

func (f *frameReader) fillNextFrame() error {
	var hdrBuf [4]byte
	if _, err := io.ReadFull(f.r, hdrBuf[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			f.hitEOF = true
			return errBackupTruncated
		}
		return err
	}
	hdr := binary.BigEndian.Uint32(hdrBuf[:])
	final := hdr&finalFrameBit != 0
	length := int(hdr &^ finalFrameBit)
	if length < 0 || length > backupChunkSize+128 {
		// 128 is plenty for the GCM tag overhead even after slack;
		// any larger and the file is malformed (or being fuzzed).
		return fmt.Errorf("backup frame length %d out of range", length)
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(f.r, payload); err != nil {
			f.hitEOF = true
			return errBackupTruncated
		}
	}
	if f.aead != nil {
		nonce := makeFrameNonce(f.nonceBase, f.counter)
		opened, err := f.aead.Open(nil, nonce, payload, nil)
		if err != nil {
			return fmt.Errorf("backup frame %d auth failed (wrong passphrase or corrupt file): %w", f.counter, err)
		}
		f.buf = opened
	} else {
		f.buf = payload
	}
	f.cursor = 0
	f.counter++
	f.doneFinal = final
	return nil
}

// makeFrameNonce builds a per-frame nonce from a random base nonce
// (12 bytes — generated once at backup time) XORed with the frame
// counter in the trailing 8 bytes. The XOR keeps the leading 4 bytes
// of the base nonce intact (per-backup randomness) while ensuring no
// two frames within a backup ever reuse the same nonce, which would
// catastrophically break GCM.
func makeFrameNonce(base [backupNonceBas]byte, counter uint64) []byte {
	out := make([]byte, backupNonceBas)
	copy(out, base[:])
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	for i := 0; i < 8; i++ {
		out[4+i] ^= ctr[i]
	}
	return out
}
