/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2016 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2016 The OpenNMS Group, Inc.
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

package org.opennms.smoketest;

import org.junit.Test;

public class NRTGraphIT extends OpenNMSSeleniumTestCase {
    @Test
    public void canLoadGraph() throws Exception {
        // Request a known graph with an invalid resource id
        m_driver.get(getBaseUrl() + "opennms/graph/nrtg.jsp?resourceId=node[999].nodeSnmp[]&report=mib2.tcpopen");
        // The graph should be rendered
        findElementByXpath("//div[@class='flot-datatable-tabs']");
        // It won't have any data, but this is sufficient to very that all of the required
        // Javascript files have been loaded, and the AJAX call to get the graph was successful
    }
}
