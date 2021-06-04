/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package org.mitre.discovery.util;

import com.google.common.base.Strings;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Provides utility methods for normalizing and parsing URIs for use with Webfinger Discovery.
 *
 * @author wkim
 */
@Slf4j
public class WebfingerURLNormalizer {

	public static final String HTTPS = "https";
	public static final String ACCT = "acct";
	public static final String HTTP = "http";
	public static final String MAILTO = "mailto";
	public static final String TEL = "tel";
	public static final String DEVICE = "device";

	// pattern used to parse user input; we can't use the built-in java URI parser
	private static final Pattern pattern = Pattern.compile("^" +
			"((" + HTTPS + '|' + HTTP + '|' + ACCT + '|' + MAILTO + '|' + TEL + '|' + DEVICE + "):(//)?)?" + // scheme
			"(" +
			"(([^@]+)@)?" + // userinfo
			"(([^?#:/]+)" + // host
			"(:(\\d*))?)" + // port
			")" +
			"([^?#]+)?" + // path
			"(\\?([^#]+))?" + // query
			"(#(.*))?" +  // fragment
			"$"
			);

	/**
	 * Normalize the resource string as per OIDC Discovery.
	 * @param identifier
	 * @return the normalized string, or null if the string can't be normalized
	 */
	public static UriComponents normalizeResource(String identifier) {
		// try to parse the URI
		// NOTE: we can't use the Java built-in URI class because it doesn't split the parts appropriately

		if (StringUtils.isEmpty(identifier)) {
			log.warn("Can't normalize null or empty URI: " + identifier);
			return null;
		} else {
			UriComponentsBuilder builder = UriComponentsBuilder.newInstance();

			Matcher m = pattern.matcher(identifier);
			if (m.matches()) {
				builder.scheme(m.group(2));
				builder.userInfo(m.group(6));
				builder.host(m.group(8));
				String port = m.group(10);
				if (!StringUtils.isEmpty(port)) {
					builder.port(Integer.parseInt(port));
				}
				builder.path(m.group(11));
				builder.query(m.group(13));
				builder.fragment(m.group(15)); // we throw away the hash, but this is the group it would be if we kept it
			} else {
				log.warn("Parser couldn't match input: '{}'", identifier);
				return null;
			}

			UriComponents n = builder.build();

			if (!StringUtils.hasText(n.getScheme())) {
				if (StringUtils.hasText(n.getUserInfo()) && !StringUtils.hasText(n.getPath())
						&& !StringUtils.hasText(n.getQuery()) && n.getPort() < 0)
				{
					// scheme empty, userinfo is not empty, path/query/port are empty, set to "acct" (rule 2)
					builder.scheme(ACCT);
				} else {
					// scheme is empty, but rule 2 doesn't apply, set scheme to "https" (rule 3)
					builder.scheme(HTTPS);
				}
			}
			// fragment must be stripped (rule 4)
			builder.fragment(null);
			return builder.build();
		}
	}

	public static String serializeURL(UriComponents uri) {
		if (uri == null) {
			return null;
		}

		String scheme = uri.getScheme();
		if (StringUtils.hasText(scheme) && isSchemeNonHttp(scheme)) {
			// serializer copied from HierarchicalUriComponents but with "//" removed
			StringBuilder uriBuilder = new StringBuilder();

			uriBuilder.append(scheme).append(':');

			String userInfo = uri.getUserInfo();
			String host = uri.getHost();
			if (StringUtils.hasText(userInfo)) {
				uriBuilder.append(userInfo).append('@');
			}
			if (StringUtils.hasText(host)) {
				uriBuilder.append(host);
			}

			int port = uri.getPort();
			if (port > -1) {
				uriBuilder.append(':').append(port);
			}

			String path = uri.getPath();
			if (StringUtils.hasText(path)) {
				if (uriBuilder.length() != 0 && path.charAt(0) != '/') {
					uriBuilder.append('/');
				}
				uriBuilder.append(path);
			}

			String query = uri.getQuery();
			if (StringUtils.hasText(query)) {
				uriBuilder.append('?').append(query);
			}

			String fragment = uri.getFragment();
			if (StringUtils.hasText(fragment)) {
				uriBuilder.append('#').append(fragment);
			}

			return uriBuilder.toString();
		} else {
			return uri.toUriString();
		}
	}

	private static boolean isSchemeNonHttp(String scheme) {
		return DEVICE.equals(scheme) || ACCT.equals(scheme) || TEL.equals(scheme) || MAILTO.equals(scheme);
	}

}
