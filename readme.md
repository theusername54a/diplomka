Z NIST jsem se podival na oficialni stranky SPHINCS+
https://sphincs.org/index.html

Tam jsem nasel odkaz na jejich repozitar na github, kde maji jejich implementaci spihncs+ pro Python
https://github.com/sphincs/pyspx

staci naistalovat knihovnu pyspx nastrojem pip.

Rodina SPHINCS+ ma nekolik algoritmu, ktere se lisi pouzitou hashovaci funkci. 
haraka_128f  haraka_192f  haraka_256f sha2_128f sha2_192f  sha2_256f  shake_128f  shake_192f  shake_256f
haraka_128s haraka_192s haraka_256s sha2_128s sha2_192s sha2_256s shake_128s shake_192s  shake_256s

Haraka_xxxf (xxx je 128, 192 nebo 256): Tyto verze používají hashovací funkci Haraka s různými délkami výstupu (128, 192 nebo 256 bitů). Haraka je konstrukce kryptografické hashovací funkce, která byla navržena pro rychlost a bezpečnost.

SHA2_xxxf (xxx je 128, 192 nebo 256): Tyto verze používají standardní hashovací funkce SHA-2 (Secure Hash Algorithm 2) s různými délkami výstupu (128, 192 nebo 256 bitů).

SHAKE_xxxf (xxx je 128, 192 nebo 256): Tyto verze používají SHA-3 variantu SHAKE (Secure Hash Algorithm KECCAK) s různými délkami výstupu (128, 192 nebo 256 bitů). SHAKE umožňuje generovat libovolně dlouhé hashovací hodnoty.

Haraka_xxxs, SHA2_xxxs, SHAKE_xxxs (xxx je 128, 192 nebo 256): Tyto verze jsou stejné jako jejich odpovídající "f" varianty, ale s optimalizacemi pro snížení velikosti veřejných klíčů a podpisů. To znamená, že generované klíče a podpisy jsou kratší, což může být výhodné v prostředích s omezenými zdroji.