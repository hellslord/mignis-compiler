RESULT = mignis

LIBS = str

SOURCES = \
  mast.mli \
  parser.mli parser.mly lexer.mll \
  scope.ml \
  compiler.ml \
  mignis.ml
  
OCAMLMAKEFILE = OCamlMakefile
include $(OCAMLMAKEFILE)
