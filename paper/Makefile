# Build the paper. Requires latexmk + TeX Live (BasicTeX works: natbib, booktabs).
.PHONY: all clean
all:
	latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex 2>/dev/null || tectonic main.tex
clean:
	latexmk -C
