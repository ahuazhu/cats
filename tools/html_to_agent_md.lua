-- Convert Cats' self-contained visual HTML documents into compact Markdown.
-- The HTML embeds large SVG diagrams as data URIs and uses many layout-only
-- div/span elements. Keep semantic text and leave numbered diagram markers for
-- a human-maintained Mermaid or text equivalent.

local diagram_count = 0

local function has_class(element, expected)
  for _, class_name in ipairs(element.classes) do
    if class_name == expected then
      return true
    end
  end
  return false
end

function Div(element)
  if has_class(element, "diagram-frame") then
    diagram_count = diagram_count + 1
    return pandoc.Para({pandoc.Str("[AGENT-DIAGRAM-" .. diagram_count .. "]")})
  end
  return element.content
end

function Span(element)
  return element.content
end

function Image(element)
  if string.match(element.src, "^data:image/") then
    return {}
  end
  return element
end

function Meta(metadata)
  metadata.viewport = nil
  metadata.audience = "AI agents and implementers"
  metadata.source_format = "Generated from the companion visual HTML; Mermaid/text diagrams are maintained in Markdown"
  return metadata
end
