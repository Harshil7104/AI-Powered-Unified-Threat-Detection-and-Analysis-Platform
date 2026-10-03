import { Navigate } from "react-router-dom";

function ProtectedRoute({ children }) {
  const isLoggedIn = localStorage.getItem("isLoggedIn") === "true";
  const token = localStorage.getItem("token");

  if (!isLoggedIn || !token) {
    return <Navigate to="/" replace />;
  }

  return children;
}

export default ProtectedRoute;