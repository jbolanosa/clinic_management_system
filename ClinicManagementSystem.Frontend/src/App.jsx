import { AuthProvider } from "./auth/providers/AuthProvider";
import { AppRouter } from "./router/AppRouter";

export const App = () => {

  return (
    <AuthProvider>
      <AppRouter/>
    </AuthProvider>
  )
}