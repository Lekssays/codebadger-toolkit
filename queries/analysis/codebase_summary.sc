// Get codebase summary statistics
cpg.metaData.map(_ => (
  cpg.file.size,
  cpg.method.size,
  cpg.method.isExternal(false).size,
  cpg.call.size,
  cpg.literal.size
)).toJsonPretty
