package com.example

object Tester extends App {

  val jwtToken = TokenService.createJWT()
  
  val tokenAfterParse = TokenService.parseJWT(jwtToken.toString)

  println(tokenAfterParse)

}
