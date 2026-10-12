
dist_man1_MANS = asn1c.1 unber.1 enber.1
EXTRA_DIST = asn1c.man.md unber.man.md enber.man.md

if HAVE_PANDOC

# Keep literal double hyphens in option names such as --rust.
PANDOC_OPTIONS= --from markdown-smart --to man  \
		--variable header="Version ${VERSION}"  \
		--variable adjusting:l                  \
		--variable hyphenate:""                 \
		--standalone

%.1: %.man.md
	${PANDOC} ${PANDOC_OPTIONS} -o $@ $<

endif

