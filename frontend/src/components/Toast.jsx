export default function Toast({ toast }) {
  if (!toast) return null;
  return (
    <div className={`toast ${toast.danger ? "toast-danger" : ""} toast-visible`} role="status">
      {toast.message}
    </div>
  );
}
