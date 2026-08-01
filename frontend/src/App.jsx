import { BrowserRouter, Routes, Route } from "react-router-dom";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import UrlScan from "./pages/UrlScan";
import EmailScan from "./pages/EmailScan";
import FileScan from "./pages/FileScan";
import AiChat from "./pages/AiChat";
import Reports from "./pages/Reports";
import ProtectedRoute from "./components/ProtectedRoute";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Login />} />
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/url-scan"
          element={
            <ProtectedRoute>
              <UrlScan />
            </ProtectedRoute>
          }
        />
        <Route
          path="/email-scan"
          element={
            <ProtectedRoute>
              <EmailScan />
            </ProtectedRoute>
          }
        />
        <Route
          path="/file-scan"
          element={
            <ProtectedRoute>
              <FileScan />
            </ProtectedRoute>
          }
        />
        <Route
          path="/ai-chat"
          element={
            <ProtectedRoute>
              <AiChat />
            </ProtectedRoute>
          }
        />
        <Route
          path="/reports"
          element={
            <ProtectedRoute>
              <Reports />
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}

export default App;