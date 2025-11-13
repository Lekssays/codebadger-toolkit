// Find function/method calls with optional filters// Find calls in the CPG

cpg.call// Parameters: caller_pattern (optional), callee_pattern (optional), limit

  {%- if callee_pattern %}

  .name("{{ callee_pattern }}")cpg.call

  {%- endif %}  {%- if callee_pattern %}

  {%- if caller_pattern %}  .name("{{ callee_pattern }}")

  .where(_.method.name("{{ caller_pattern }}"))  {%- endif %}

  {%- endif %}  {%- if caller_pattern %}

  .map(c => (c.method.name, c.name, c.code, c.method.filename, c.lineNumber.getOrElse(-1)))  .where(_.method.name("{{ caller_pattern }}"))

  .dedup.take({{ limit }})  {%- endif %}

  .map(c => (c.method.name, c.name, c.code, c.method.filename, c.lineNumber.getOrElse(-1)))
  .dedup.take({{ limit }}).toJsonPretty
