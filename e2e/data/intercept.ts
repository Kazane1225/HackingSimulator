/** Scenario data for the SQLi login used to exercise the intercepting proxy. */
export const SQLI_LOGIN = {
  lab: "sqli",
  appUser: "admin",
  wrongPassword: "wrong",
  /** Lv1 exploit: closes the quote and comments out the password check. */
  tamperedUsername: "admin'-- ",
  usernameParam: "username",
} as const;
