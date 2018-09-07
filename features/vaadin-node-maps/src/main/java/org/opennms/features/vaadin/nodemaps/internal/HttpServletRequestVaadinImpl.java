/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2013-2014 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2014 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * OpenNMS(R) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OpenNMS(R).  If not, see:
 *      http://www.gnu.org/licenses/
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/

package org.opennms.features.vaadin.nodemaps.internal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;

import org.opennms.web.api.OnmsHeaderProvider;

import com.vaadin.server.VaadinRequest;
import com.vaadin.server.VaadinServletRequest;
import com.vaadin.server.WrappedHttpSession;
import com.vaadin.server.WrappedSession;

/**
 * This class creates an {@link HttpServletRequest} object that delegates all calls to
 * a {@link VaadinRequest} instance. This is used so that we can fetch the header HTML
 * from an {@link OnmsHeaderProvider}.
 *
 * TODO: Refactor into a common class.
 */
public class HttpServletRequestVaadinImpl implements HttpServletRequest {

    private final VaadinRequest m_request;
    private URL m_url;

    public HttpServletRequestVaadinImpl(VaadinRequest request, URL url) {
        m_request = request;
        m_url = url;
    }

    @Override
    public String getAuthType() {
        return m_request.getAuthType();
    }

    @Override
    public String getContextPath() {
        return m_request.getContextPath();
    }

    @Override
    public Cookie[] getCookies() {
        return m_request.getCookies();
    }

    @Override
    public long getDateHeader(String name) {
        return m_request.getDateHeader(name);
    }

    @Override
    public String getHeader(String name) {
        return m_request.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        return m_request.getHeaderNames();
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        return m_request.getHeaders(name);
    }

    @Override
    public int getIntHeader(String name) {
        return Integer.parseInt(m_request.getHeader(name));
    }

    @Override
    public String getMethod() {
        return m_request.getMethod();
    }

    @Override
    public String getPathInfo() {
        return m_request.getPathInfo();
    }

    @Override
    public String getPathTranslated() {
        return null;
    }

    @Override
    public String getQueryString() {
        return null;
    }

    @Override
    public String getRemoteUser() {
        return m_request.getRemoteUser();
    }

    @Override
    public String getRequestURI() {
        return getServletRequest().get().getRequestURI();
    }

    @Override
    public StringBuffer getRequestURL() {
        return getServletRequest().get().getRequestURL();
    }

    @Override
    public String getRequestedSessionId() {
        return getServletRequest().get().getRequestedSessionId();
    }

    @Override
    public String getServletPath() {
        return getServletRequest().get().getServletPath();
    }

    @Override
    public HttpSession getSession() {
        return getHttpSession(false);
    }

    /**
     * @throws UnsupportedOperationException
     */
    @Override
    public HttpSession getSession(final boolean create) {
        return getHttpSession(create);
    }

    @Override
    public Principal getUserPrincipal() {
        return m_request.getUserPrincipal();
    }

    @Override
    public boolean isRequestedSessionIdFromCookie() {
        return getServletRequest().get().isRequestedSessionIdFromCookie();
    }

    @Override
    public boolean isRequestedSessionIdFromURL() {
        return getServletRequest().get().isRequestedSessionIdFromURL();
    }

    @Override
    public boolean isRequestedSessionIdFromUrl() {
        return getServletRequest().get().isRequestedSessionIdFromUrl();
    }

    @Override
    public boolean isRequestedSessionIdValid() {
        return getServletRequest().get().isRequestedSessionIdValid();
    }

    @Override
    public boolean isUserInRole(String role) {
        return m_request.isUserInRole(role);
    }

    @Override
    public Object getAttribute(String name) {
        return m_request.getAttribute(name);
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        return m_request.getAttributeNames();
    }

    @Override
    public String getCharacterEncoding() {
        return m_request.getCharacterEncoding();
    }

    @Override
    public int getContentLength() {
        return m_request.getContentLength();
    }

    @Override
    public String getContentType() {
        return m_request.getContentType();
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        return getServletRequest().get().getInputStream();
    }

    @Override
    public String getLocalAddr() {
        return getServletRequest().get().getLocalAddr();
    }

    @Override
    public String getLocalName() {
        return getServletRequest().get().getLocalName();
    }

    @Override
    public int getLocalPort() {
        return getServletRequest().get().getLocalPort();
    }

    @Override
    public Locale getLocale() {
        return m_request.getLocale();
    }

    @Override
    public Enumeration<Locale> getLocales() {
        return m_request.getLocales();
    }

    @Override
    public String getParameter(String name) {
        return m_request.getParameter(name);
    }

    @Override
    public Map<String,String[]> getParameterMap() {
        return m_request.getParameterMap();
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return getServletRequest().get().getParameterNames();
    }

    @Override
    public String[] getParameterValues(final String name) {
        return getServletRequest().get().getParameterValues(name);
    }

    @Override
    public String getProtocol() {
        return getServletRequest().get().getProtocol();
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return m_request.getReader();
    }

    @Override
    public String getRealPath(final String path) {
        return getServletRequest().get().getRealPath(path);
    }

    @Override
    public String getRemoteAddr() {
        return m_request.getRemoteAddr();
    }

    @Override
    public String getRemoteHost() {
        return m_request.getRemoteHost();
    }

    @Override
    public int getRemotePort() {
        return m_request.getRemotePort();
    }

    @Override
    public RequestDispatcher getRequestDispatcher(final String path) {
        return getServletRequest().get().getRequestDispatcher(path);
    }

    @Override
    public String getScheme() {
        return m_url.getProtocol();
    }

    @Override
    public String getServerName() {
        return m_url.getHost();
    }

    @Override
    public int getServerPort() {
        return m_url.getPort();
    }

    @Override
    public boolean isSecure() {
        return m_request.isSecure();
    }

    @Override
    public void removeAttribute(String name) {
        m_request.removeAttribute(name);
    }

    @Override
    public void setAttribute(String name, Object o) {
        m_request.setAttribute(name, o);
    }

    @Override
    public void setCharacterEncoding(final String env) throws UnsupportedEncodingException {
        getServletRequest().get().setCharacterEncoding(env);
    }

    @Override
    public AsyncContext getAsyncContext() {
        return getServletRequest().get().getAsyncContext();
    }

    @Override
    public DispatcherType getDispatcherType() {
        return getServletRequest().get().getDispatcherType();
    }

    @Override
    public ServletContext getServletContext() {
        return getServletRequest().get().getServletContext();
    }

    @Override
    public boolean isAsyncStarted() {
        return getServletRequest().get().isAsyncStarted();
    }

    @Override
    public boolean isAsyncSupported() {
        return getServletRequest().get().isAsyncSupported();
    }

    @Override
    public AsyncContext startAsync() throws IllegalStateException {
        return getServletRequest().get().startAsync();
    }

    @Override
    public AsyncContext startAsync(final ServletRequest request, final ServletResponse response) throws IllegalStateException {
        return getServletRequest().get().startAsync(request, response);
    }

    @Override
    public boolean authenticate(final HttpServletResponse response) throws IOException, ServletException {
        return getServletRequest().get().authenticate(response);
    }

    @Override
    public Part getPart(final String arg0) throws IOException, ServletException {
        return getServletRequest().get().getPart(arg0);
    }

    @Override
    public Collection<Part> getParts() throws IOException, ServletException {
        return getServletRequest().get().getParts();
    }

    @Override
    public void login(final String user, final String password) throws ServletException {
        getServletRequest().get().login(user, password);
    }

    @Override
    public void logout() throws ServletException {
        getServletRequest().get().logout();
    }

    @Override
    public long getContentLengthLong() {
        return m_request.getContentLength();
    }

    @Override
    public String changeSessionId() {
        return getServletRequest().get().changeSessionId();
    }

    @Override
    public <T extends HttpUpgradeHandler> T upgrade(final Class<T> handlerClass) throws IOException, ServletException {
        return getServletRequest().get().upgrade(handlerClass);
    }

    private Optional<VaadinServletRequest> getServletRequest() {
        if (m_request instanceof VaadinServletRequest) {
            return Optional.ofNullable((VaadinServletRequest)m_request);
        }
        return Optional.empty();
    }

    private HttpSession getHttpSession(final boolean create) {
        final WrappedSession wrappedSession = m_request.getWrappedSession(create);
        if (wrappedSession instanceof WrappedHttpSession) {
            return ((WrappedHttpSession)wrappedSession).getHttpSession();
        }
        return null;
    }
}
