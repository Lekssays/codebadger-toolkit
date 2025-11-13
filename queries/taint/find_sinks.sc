// Find taint sinks (dangerous functions)// Find taint sinks (dangerous functions) in the code

cpg.call.name("{{ patterns }}")// Parameters: patterns (joined by |), filename (optional), limit

  {%- if filename %}

  .where(_.file.name(".*{{ filename }}.*"))cpg.call.name("{{ patterns }}")

  {%- endif %}  {%- if filename %}

  .map(c => (c.id, c.name, c.code, c.file.name.headOption.getOrElse("unknown"), c.lineNumber.getOrElse(-1), c.method.fullName))  .where(_.file.name(".*{{ filename }}.*"))

  .take({{ limit }})  {%- endif %}

  .map(c => (c.id, c.name, c.code, c.file.name.headOption.getOrElse("unknown"), c.lineNumber.getOrElse(-1), c.method.fullName))
  .take({{ limit }})
