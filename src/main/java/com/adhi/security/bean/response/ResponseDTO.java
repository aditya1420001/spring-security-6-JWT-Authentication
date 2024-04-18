package com.adhi.security.bean.response;


import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResponseDTO<T> {

    public ResponseDTO(T message, Integer code) {
        this.message = message;
        this.code = code;
    }

    private T message;
    private Integer code;

}
