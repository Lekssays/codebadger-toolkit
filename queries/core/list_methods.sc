// List all methods in the CPG with optional filters// List all methods in the CPG

cpg.method// Parameters: include_external, name_pattern, file_pattern, callee_pattern, limit

  {%- if not include_external %}

  .isExternal(false)cpg.method

  {%- endif %}  {%- if not include_external %}

  {%- if name_pattern %}  .isExternal(false)

  .name("{{ name_pattern }}")  {%- endif %}

  {%- endif %}  {%- if name_pattern %}

  {%- if file_pattern %}  .name("{{ name_pattern }}")

  .where(_.file.name("{{ file_pattern }}"))  {%- endif %}

  {%- endif %}  {%- if file_pattern %}

  {%- if callee_pattern %}  .where(_.file.name("{{ file_pattern }}"))

  .where(_.callOut.name("{{ callee_pattern }}"))  {%- endif %}

  {%- endif %}  {%- if callee_pattern %}

  .map(m => (m.name, m.id, m.fullName, m.signature, m.filename, m.lineNumber.getOrElse(-1), m.isExternal))  .where(_.callOut.name("{{ callee_pattern }}"))

  .dedup.take({{ limit }}).l  {%- endif %}

  .map(m => (m.name, m.id, m.fullName, m.signature, m.filename, m.lineNumber.getOrElse(-1), m.isExternal))
  .dedup.take({{ limit }}).l
