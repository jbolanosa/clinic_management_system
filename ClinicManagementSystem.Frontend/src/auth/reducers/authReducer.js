import { INITIALIZE, LOGIN_SUCCESS, REGISTER_SUCCESS, LOGOUT, AUTH_ERROR, REFRESH_TOKEN } from "../actions/types";

export const initialState = {
  isAuthenticated: false,
  user: null,
  token: null,
  refreshToken: null,
  loading: true,
  error: null,
}

export const authReducer = ( state, action ) => {

  switch( action.type ){
    case INITIALIZE:
      return { ...state, ...action.payload, loading: false };
    case LOGIN_SUCCESS:
      return {
        ...state,
        isAuthenticated: true,
        user: action.payload.user,
        token: action.payload.token,
        refreshToken: action.payload.refreshToken,
        error: null,
      };
    case LOGOUT:
      return { ...initialState, loading: false };
    case AUTH_ERROR:
      return { ...state, error: action.payload };
    case REFRESH_TOKEN:
      return {
        ...state,
        token: action.payload.token,
        refreshToken: action.payload.refreshToken,
      };
    default:
      return state;
  }
}