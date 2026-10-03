import { BrowserRouter, Routes, Route } from "react-router-dom";
import Login from "./pages/login";
import Dashboard from "./pages/dashboard";
import UrlScan from "./pages/urlscan";
import EmailScan from "./pages/emailscan";
import FileScan from "./pages/filescan";
import AiChat from "./pages/aichat";
import Reports from "./pages/reports";
import ProtectedRoute from "./components/protectedroute";

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