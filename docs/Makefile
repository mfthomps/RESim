RESim-UsersGuide.pdf: RESim.tex
	latex RESim
	pdflatex RESim
	pdflatex RESim
	mv RESim.pdf RESim-UsersGuide.pdf
RESimRemote.pdf: RESimRemote.tex
	latex RESimRemote
	pdflatex RESimRemote
	pdflatex RESimRemote

all: RESim-UsersGuide.pdf RESimRemote.pdf
clean:
	rm -fr auto
	rm -f *.aux *.log *.ps *.dvi
