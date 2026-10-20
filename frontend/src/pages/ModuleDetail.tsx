import { useParams } from "react-router-dom";

export default function ModuleDetail() {
  const { id } = useParams<{ id: string }>();
  return (
    <>
      <h2>{id}</h2>
      <p className="sub">Module detail lands here in the next task.</p>
    </>
  );
}
