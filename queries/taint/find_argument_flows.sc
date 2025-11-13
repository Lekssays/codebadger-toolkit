// Find argument flows between source and sink calls
cpg.call.name("{{ source_name }}")
  .flatMap(src => {
    val argExpr = src.argument.l.lift({{ arg_index }}).map(_.code).getOrElse("<no-arg>");
    cpg.call.name("{{ sink_name }}")
      .filter(sink => sink.argument.l.size > {{ arg_index }} && sink.argument.l({{ arg_index }}).code == argExpr)
      .map(sink => (src, sink, argExpr))
  })
  .map(t => (t._1.name, t._1.code, t._1.lineNumber.getOrElse(-1), t._2.name, t._2.code, t._2.lineNumber.getOrElse(-1), t._3))
  .take({{ limit }})
