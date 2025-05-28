import { useEffect, useReducer } from "react"
import { authReducer, initialState } from "../reducers/authReducer"
import { INITIALIZE, LOGIN_SUCCESS, REGISTER_SUCCESS, LOGOUT, AUTH_ERROR, REFRESH_TOKEN } from "../actions/types";
import { AuthContext } from "../context/AuthContext";

export const AuthProvider = ({ children }) => {
  const [ state, dispatch ] = useReducer(authReducer, initialState);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const refreshToken = localStorage.getItem('refreshToken');
    const user = JSON.parse(localStorage.getItem('user'));

    if(token && refreshToken && user){
      dispatch({
        type: INITIALIZE,
        payload: {isAuthenticated: true, token, refreshToken, user},
      });
    } else {
        dispatch({ type: INITIALIZE, payload: initialState });
    }

  }, []);

  return (
    <AuthContext.Provider value={{
      ...state
    }}>
      { children }
    </AuthContext.Provider>
  );
  
}