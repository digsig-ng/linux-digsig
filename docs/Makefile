# I love documentation that ships with a Makefile...

default:
	latex digsig.tex
	pdflatex digsig.tex

pdf: digsig.pdf ELF-Format.eps System-call.eps
	ps2pdf ELF-Format.eps
	ps2pdf System-call.eps 
	pdflatex digsig.tex

clean:
	rm -f *.aux *.dvi *.log *.pdf


