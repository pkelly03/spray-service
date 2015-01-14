package com.example

import akka.actor.Actor
import spray.json.DefaultJsonProtocol
import spray.routing._

// we don't implement our route structure directly in the service actor because
// we want to be able to test it independently, without having to spin up an actor
class MyServiceActor extends Actor with MyService {

  def actorRefFactory = context

  def receive = runRoute(myRoute)
}
case class Message(id: String, content: String)

object MyServiceJsonProtocol extends DefaultJsonProtocol {
  implicit val messageFormat = jsonFormat2(Message)
}

// this trait defines our service behavior independently from the service actor
trait MyService extends HttpService {
  import spray.httpx.SprayJsonSupport._
  import MyServiceJsonProtocol._

  val myRoute =
    get {
      path("test") {
        complete {
          Message("id-1", "sample message contents")
        }
      }
    } ~
      path("test") {
        post {
          complete {
            "Success"
          }
        }
      }
}