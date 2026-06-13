import { sourceLabel } from "../utils/helpers.js";

export default function SourceBadge({ source }) {
  return <span className="source-badge">{sourceLabel(source)}</span>;
}
