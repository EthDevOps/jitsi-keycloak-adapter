// -----------------------------------------------------------------------------
// This function creates the context inside JWT's payload. It gets userInfo
// (which comes from Keycloak) as parameter.
//
// Update the codes according to your requirements. Welcome to TypeScript :)
// -----------------------------------------------------------------------------

export function createContext(userInfo: Record<string, unknown>) {
  const context = {
    user: {
      id: userInfo.sub,
      name: userInfo.given_name || "",
      email: userInfo.email || "",
      lobby_bypass: userInfo.lobby_bypass || false,
      security_bypass: userInfo.security_bypass || false,
      affiliation: userInfo.affiliation || "member",
    },
  };

  return context;
}
