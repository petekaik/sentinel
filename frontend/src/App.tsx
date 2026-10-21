import { NavLink, Route, Routes } from "react-router-dom";
import Overview from "./pages/Overview";
import Modules from "./pages/Modules";
import ModuleDetail from "./pages/ModuleDetail";
import Settings from "./pages/Settings";
import Incidents from "./pages/Incidents";
import Proposals from "./pages/Proposals";
import Intelligence from "./pages/Intelligence";

export default function App() {
  return (
    <div className="wrap">
      <header><h1>Sentinel</h1></header>
      <nav>
        <NavLink to="/" end>Overview</NavLink>
        <NavLink to="/modules">Modules</NavLink>
        <NavLink to="/settings">Settings</NavLink>
        <NavLink to="/incidents">Incidents</NavLink>
        <NavLink to="/proposals">Proposals</NavLink>
        <NavLink to="/intelligence">Intelligence</NavLink>
      </nav>
      <main>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/modules" element={<Modules />} />
          <Route path="/modules/:id" element={<ModuleDetail />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/proposals" element={<Proposals />} />
          <Route path="/intelligence" element={<Intelligence />} />
        </Routes>
      </main>
    </div>
  );
}
