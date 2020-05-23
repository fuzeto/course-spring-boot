package br.com.alura.forum.controller;

import br.com.alura.forum.dto.TopicoDto;
import br.com.alura.forum.model.Curso;
import br.com.alura.forum.model.Topico;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class TopicoController {

    @RequestMapping("/topicos")
    public List<TopicoDto> lista() {

        Topico topico = new Topico("Dúvida", "Dúvida sobre Spring Boot", new Curso("Spring boot", "Programação"));

        return TopicoDto.converter(Arrays.asList(topico, topico, topico));
    }
}
