// Find program slice from a specific call node// Program slicing - find all statements affecting a variable

// This complex query needs to be generated inline in the tool// Parameters: {{variable_name}}, {{method_name}}, {{limit}}

// Parameters are passed to the tool which builds the full query

// Because it requires complex JSON escaping and conditional logiccpg.method("{{method_name}}")

  .local("{{variable_name}}")
  .reachingDef
  .map(r => (r.code, r.lineNumber.getOrElse(-1), r.file.name.getOrElse("")))
  .dedup
  .take({{limit}})
  .toJsonPretty
