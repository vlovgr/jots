import laika.api.bundle.ExtensionBundle
import laika.ast.BlockSequence
import laika.ast.CodeBlock
import laika.ast.RewriteAction.Replace
import laika.ast.RewriteAction.Retain
import laika.ast.RewriteRules
import laika.ast.Styles
import laika.ast.Text

/**
  * Renders left-to-right Mermaid flowcharts as top-down when
  * the available width is narrow.
  *
  * Every `graph LR` (or `flowchart LR`) Mermaid code block
  * is copied into a left-to-right and a top-down variant,
  * and CSS rules show one of them based on width.
  */
object ResponsiveMermaid extends ExtensionBundle {
  val description: String = "Responsive Mermaid flowcharts"

  private val leftToRight = """(?m)^([ \t]*(?:graph|flowchart)[ \t]+)LR\b""".r

  override def rewriteRules: RewriteRules.RewritePhaseBuilder =
    RewriteRules.forBlocks {
      case block: CodeBlock if block.language == "mermaid" =>
        val diagram = block.extractText
        val topDown = leftToRight.replaceFirstIn(diagram, "$1TD")
        if (topDown == diagram) Retain
        else
          Replace(
            BlockSequence(
              Seq(
                BlockSequence(Seq(block), Styles("mermaid-lr")),
                BlockSequence(Seq(block.withContent(Seq(Text(topDown)))), Styles("mermaid-td"))
              ),
              Styles("mermaid-responsive")
            )
          )
    }.asDefaultPhaseBuilder
}
