import hg_keywords

keywords = hg_keywords.keywords(
    "$branches:  $",
    "$node: 83f8cf753f41eb3d53d3d4b95a8cc56c18b0c3fc $",
    "$rev: 8 $",
    "$tags: tip $"
    )

version = "dev_%s_%s" % tuple([keywords[x] for x in 'rev', 'node'])
