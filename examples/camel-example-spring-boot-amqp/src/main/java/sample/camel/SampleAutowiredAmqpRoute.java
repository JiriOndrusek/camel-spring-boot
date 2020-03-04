/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.camel;

import org.apache.camel.builder.RouteBuilder;
import org.apache.qpid.jms.JmsConnectionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@Component
public class SampleAutowiredAmqpRoute extends RouteBuilder {

    @Autowired JmsConnectionFactory amqpConnectionFactory;
    @Bean
    public org.apache.camel.component.amqp.AMQPComponent amqpConnection() {
        org.apache.camel.component.amqp.AMQPComponent amqp = new org.apache.camel.component.amqp.AMQPComponent();
        amqp.setConnectionFactory(amqpConnectionFactory);
        return amqp;
    }

    @Override
    public void configure() throws Exception {
        from("file:src/main/data?noop=true")
            .to("amqp:queue:SCIENCEQUEUE");

//        from("direct:start")
//                .to("undertow:http://www.google.com");

        //todo is created by route builder somehow
        from("async-api:///api-doc")
            .to("async-api:///api-doc");
//            .to("log:foo");


        /*from("timer:bar")
            .setBody(constant("Hello from Camel"))
            .to("amqp:queue:SCIENCEQUEUE");*/
    }

}
