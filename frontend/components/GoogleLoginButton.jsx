import React, { useEffect, useRef } from "react";
import axios from "axios";

export default function GoogleLoginButton({ onSuccess, onError }) {
  const buttonDivRef = useRef(null);

  useEffect(() => {
    const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID;

    if (!clientId) {
      console.warn("VITE_GOOGLE_CLIENT_ID is missing in frontend/.env");
      return;
    }

    const handleCredentialResponse = async (response) => {
      try {
        // Send Google's ID Token (credential) directly to backend
        const res = await axios.post("/api/auth/google", {
          token: response.credential,
          id_token: response.credential,
        });

        // Store access token and user info
        localStorage.setItem("token", res.data.access_token);
        const userData = res.data.user || {
          username: res.data.username,
          role: res.data.role,
          user_id: res.data.user_id,
        };
        localStorage.setItem("user", JSON.stringify(userData));

        if (onSuccess) onSuccess(res.data);
      } catch (err) {
        console.error("Google authentication failed:", err);
        if (onError) onError(err);
      }
    };

    const initGoogle = () => {
      if (window.google?.accounts?.id && buttonDivRef.current) {
        window.google.accounts.id.initialize({
          client_id: clientId,
          callback: handleCredentialResponse,
        });

        window.google.accounts.id.renderButton(buttonDivRef.current, {
          theme: "filled_black",
          size: "large",
          shape: "rectangular",
          width: "100%",
          text: "continue_with",
        });
      }
    };

    if (window.google?.accounts?.id) {
      initGoogle();
    } else {
      const interval = setInterval(() => {
        if (window.google?.accounts?.id) {
          clearInterval(interval);
          initGoogle();
        }
      }, 200);
      return () => clearInterval(interval);
    }
  }, [onSuccess, onError]);

  return <div ref={buttonDivRef} className="w-full flex justify-center my-2" />;
}
