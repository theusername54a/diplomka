CC=/usr/bin/gcc
CFLAGS += -O3 -march=native -fomit-frame-pointer
LDFLAGS=-lcrypto

SOURCES= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c PQCgenKAT_kem.c reduce.c rng.c verify.c symmetric-shake.c
SOURCES1= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c KYBER512_keygen.c reduce.c rng.c verify.c symmetric-shake.c
SOURCES2= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c KYBER512_CTSS.c reduce.c rng.c verify.c symmetric-shake.c
SOURCES3= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c KYBER512_SS.c reduce.c rng.c verify.c symmetric-shake.c
HEADERS= api.h cbd.h fips202.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h rng.h verify.h symmetric.h

all: PQCgenKAT_kem KYBER512_keygen KYBER512_CTSS KYBER512_SS

PQCgenKAT_kem: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

KYBER512_keygen: $(HEADERS) $(SOURCES1)
	$(CC) $(CFLAGS) -o $@ $(SOURCES1) $(LDFLAGS)

KYBER512_CTSS: $(HEADERS) $(SOURCES2)
	$(CC) $(CFLAGS) -o $@ $(SOURCES2) $(LDFLAGS)

KYBER512_SS: $(HEADERS) $(SOURCES3)
	$(CC) $(CFLAGS) -o $@ $(SOURCES3) $(LDFLAGS)

.PHONY: clean

clean:
	-rm PQCgenKAT_kem KYBER512_keygen KYBER512_CTSS KYBER512_SS
