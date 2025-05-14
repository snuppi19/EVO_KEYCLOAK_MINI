package com.mtran.mvc.dto.request;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class PagingRequest {
    private int page;
    private int size;
    private String sortBy;
    private boolean isDescending;
}
