function inlineParts(text) {
  const parts = [];
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIndex = 0;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    const token = match[0];
    if (token.startsWith("**")) {
      parts.push(<strong key={`${match.index}-bold`}>{token.slice(2, -2)}</strong>);
    } else {
      parts.push(<code key={`${match.index}-code`}>{token.slice(1, -1)}</code>);
    }
    lastIndex = pattern.lastIndex;
  }
  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }
  return parts;
}

export default function MarkdownText({ text, className = "" }) {
  const lines = String(text || "").replace(/\r\n/g, "\n").split("\n");
  const blocks = [];
  let list = [];

  function flushList() {
    if (!list.length) return;
    blocks.push(
      <ul key={`list-${blocks.length}`}>
        {list.map((item, index) => (
          <li key={`${item}-${index}`}>{inlineParts(item)}</li>
        ))}
      </ul>
    );
    list = [];
  }

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) {
      flushList();
      continue;
    }
    const bullet = line.match(/^[-*]\s+(.+)$/);
    const numbered = line.match(/^\d+[.)]\s+(.+)$/);
    if (bullet || numbered) {
      list.push((bullet || numbered)[1]);
      continue;
    }
    flushList();
    blocks.push(<p key={`p-${blocks.length}`}>{inlineParts(line)}</p>);
  }
  flushList();

  return <div className={`markdown-text ${className}`}>{blocks}</div>;
}
