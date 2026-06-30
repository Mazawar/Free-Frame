package com.example.demo;

import com.example.demo.protocol.MyProtocol;
import com.example.demo.protocol.core.ProtocolRegistry;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        ProtocolRegistry.register(MyProtocol.class);
        SpringApplication.run(DemoApplication.class, args);
    }

}
