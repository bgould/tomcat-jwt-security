package it.cosenonjaviste.security.jwt.valves;

import java.io.IOException;
import java.nio.file.attribute.UserPrincipal;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

import it.cosenonjaviste.security.jwt.catalinawriters.ResponseWriter;
import it.cosenonjaviste.security.jwt.model.AuthErrorResponse;
import it.cosenonjaviste.security.jwt.utils.JwtAuthType;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import it.cosenonjaviste.security.jwt.utils.JwtTokenBuilder;
import it.cosenonjaviste.security.jwt.utils.JwtTokenVerifier;

/**
 * Perform a JWT authentication on requester resource.
 *
 * Expected a JWT token containing two additional claims over standard ones:
 * <ul>
 * 	<li><em>userId</em>: username authenticated by realm system</li>
 * 	<li><em>roles</em>: realm roles associated to username</li>
 * </ul>
 *
 * A new {@link UserPrincipal} will be created upon <tt>userId</tt> and <tt>roles</tt> values: no need to authenticate each request, user status is provided by JWT token!
 * <br>
 * Expected header for JWT token is <strong><tt>X-Auth</tt></strong>
 *
 * @author acomo
 *
 */
public class JwtTokenValve extends ValveBase {

	private JwtAuthType _authType = JwtAuthType.HEADER;

	private String _headerName = JwtConstants.AUTH_HEADER;

	private String _cookieName = "";

	private String _cookiePath = "";

	private String _cookieDomain = "";

	private boolean _cookieHttpOnly = false;

	private boolean _cookieSecure = false;

	private String secret;

	private boolean updateExpire;

	@Override
	public void invoke(Request request, Response response) throws IOException,
			ServletException {

		SecurityConstraint[] constraints = this.container.getRealm()
				.findSecurityConstraints(request, request.getContext());

		if ((constraints == null && !request.getContext().getPreemptiveAuthentication())
				|| !hasAuthContraint(constraints)) {
			this.getNext().invoke(request, response);
		} else {
			handleAuthentication(request, response);
		}

	}

	private boolean hasAuthContraint(SecurityConstraint[] constraints) {
		boolean authConstraint = true;
		for (SecurityConstraint securityConstraint : constraints) {
			authConstraint &= securityConstraint.getAuthConstraint();
		}
		return authConstraint;
	}

	private void handleAuthentication(Request request, Response response)
			throws IOException, ServletException {
		String token = getToken(request);
		if (token != null) {
			JwtTokenVerifier tokenVerifier = JwtTokenVerifier.create(secret);
			if (tokenVerifier.verify(token)) {
				request.setUserPrincipal(createPrincipalFromToken(tokenVerifier));
				request.setAuthType("TOKEN");
				if (this.updateExpire) {
					updateToken(tokenVerifier, request, response);
				}
				this.getNext().invoke(request, response);
			} else {
				sendUnauthorizedError(request, response, "Token not valid. Please login first");
			}
		} else {
			sendUnauthorizedError(request, response, "Please login first");
		}
	}

	private String getToken(Request request) {
		switch (this._authType) {
		case COOKIE:
			return getCookieToken(request);
		case HEADER:
			return getHeaderToken(request);
		default:
			throw new IllegalStateException("invalid authType: " + _authType);
		}
	}

	private String getCookieToken(Request request) {
		final String name = ensureNotBlank(this._cookieName, "cookieName");
		final Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (final Cookie cookie : request.getCookies()) {
				if (name.equals(cookie.getName())) {
					return cookie.getValue();
				}
			}
		}
		return null;
	}

	private String getHeaderToken(Request request) {
		return request.getHeader(ensureNotBlank(this._headerName, "headerName"));
	}

	private void updateToken(JwtTokenVerifier tokenVerifier, Request req, Response res) {
		String newToken = JwtTokenBuilder.from(tokenVerifier, secret).build();
		switch (this._authType) {
		case HEADER:
			setHeaderToken(newToken, res);
			return;
		case COOKIE:
			setCookieToken(newToken, req, res);
			return;
		}
		throw new IllegalStateException("invalid authType: " + _authType);
	}

	private void setHeaderToken(String token, Response response) {
		response.setHeader(ensureNotBlank(this._headerName, "headerName"), token);
	}

	private void setCookieToken(String token, Request req, Response response) {
		final String name = ensureNotBlank(this._cookieName, "cookieName");
		final String path = ensureNotNull(this._cookiePath, "cookiePath");
		final String domn = ensureNotNull(this._cookieDomain, "cookieDomain");
		final Cookie cookie = new Cookie(name, token);
		cookie.setPath(isBlank(path) ? req.getContextPath() + "/" : path);
		cookie.setHttpOnly(this._cookieHttpOnly);
		cookie.setSecure(this._cookieSecure);
		if (!isBlank(domn)) {
			cookie.setDomain(domn);
		}
		response.addCookie(cookie);
	}

	private GenericPrincipal createPrincipalFromToken(JwtTokenVerifier tokenVerifier) {
		return new GenericPrincipal(tokenVerifier.getUserId(), null, tokenVerifier.getRoles());
	}

	protected void sendUnauthorizedError(Request request, Response response, String message) throws IOException {
		ResponseWriter.get(request.getHeader("accept")).write(response, HttpServletResponse.SC_UNAUTHORIZED, new AuthErrorResponse(message));
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	/**
	 * Updates expire time on each request
	 *
	 * @param updateExpire
	 */
	public void setUpdateExpire(boolean updateExpire) {
		this.updateExpire = updateExpire;
	}

	/**
	 * Choose whether to check headers or cookies for token.
	 * Valid values are 'header' or 'cookie' (default: 'header')
	 * @param authType
	 */
	public void setAuthType(String authType) {
		if (isBlank(authType)) {
			this._authType = JwtAuthType.HEADER;
		} else {
			JwtAuthType match = JwtAuthType.valueOf(authType.toUpperCase());
			if (match != null) {
				this._authType = match;
			} else {
				throw new IllegalArgumentException(String.format(
					"Invalid auth type; should be one of %s (case insensitive)",
					Arrays.asList(JwtAuthType.values())
				));
			}
		}
	}

	public void setHeaderName(final String authHeaderName) {
		this._headerName = coalesce(authHeaderName, JwtConstants.AUTH_HEADER);
	}

	public void setCookieName(final String cookieName) {
		this._cookieName = coalesce(cookieName, JwtConstants.AUTH_COOKIE);
	}

	public void setCookiePath(final String cookiePath) {
		this._cookiePath = coalesce(cookiePath, "");
	}

	public void setCookieDomain(final String cookieDomain) {
		this._cookieDomain = coalesce(cookieDomain, "");
	}

	public void setCookieHttpOnly(final String httpOnly) {
		this._cookieHttpOnly = (httpOnly == null) ? false : Boolean.valueOf(httpOnly);
	}

	public void setCookieSecure(final String secure) {
		this._cookieHttpOnly = (secure == null) ? false : Boolean.valueOf(secure);
	}

	private static final String coalesce(final String s, final String dflt) {
		return isBlank(s) ? dflt : s;
	}

	private static final boolean isBlank(final String s) {
		return (s == null) ? true : s.trim().equals("");
	}

	private static final String ensureNotBlank(String s, String label) {
		if (isBlank(s)) {
			throw new IllegalStateException(label + " should not be blank.");
		}
		return s;
	}

	private static final String ensureNotNull(String s, String label) {
		if (s == null) {
			throw new IllegalStateException(label + " should not be null.");
		}
		return s;
	}
}
