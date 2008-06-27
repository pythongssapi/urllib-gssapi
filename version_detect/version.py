import hg_keywords

keywords = hg_keywords.keywords(
    "$branches$",
    "$node$",
    "$rev$",
    "$tags$"
    )

version = "dev_%s_%s" % tuple([keywords[x] for x in 'rev', 'node'])
