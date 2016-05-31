package it.cosenonjaviste.security.jwt.utils;

/**
 * Helper class for centralizing constants
 *
 * @author acomo
 *
 */
public class JwtConstants {

	/**
	 * Default name for the header storing the authentication token.
	 */
	public static final String AUTH_HEADER = "X-Auth";

	/**
	 * Default name for cookie storing the authentication token.
	 */
	public static final String AUTH_COOKIE = "auth-token";

	/**
	 * User Id claim key
	 */
	public static final String USER_ID = "userId";

	/**
	 * Roles claim key
	 */
	public static final String ROLES = "roles";

}
