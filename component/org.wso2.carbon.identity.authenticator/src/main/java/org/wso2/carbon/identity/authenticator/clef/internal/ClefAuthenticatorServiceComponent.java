/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.clef.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.authenticator.clef.ClefAuthenticator;

import java.util.Hashtable;

/**
 * @scr.component name="identity.application.authenticator.clef.component" immediate="true"
 */
public class ClefAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(ClefAuthenticatorServiceComponent.class);

    protected void activate(ComponentContext componentContext) {
        ClefAuthenticator authenticator = new ClefAuthenticator();
        Hashtable<String, String> props = new Hashtable<>();
        componentContext.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                authenticator, props);
        if (log.isDebugEnabled()) {
            log.debug("clef authenticator is activated");
        }
    }

    protected void deactivate(ComponentContext componentContext) {
        if (log.isDebugEnabled()) {
            log.debug("clef authenticator is deactivated");
        }
    }
}
