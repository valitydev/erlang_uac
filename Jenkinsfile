#!groovy
// -*- mode: groovy -*-

def finalHook = {
  runStage('store CT logs') {
    archive '_build/test/logs/'
  }
}

build('erlang_uac', 'docker-host', finalHook) {
  checkoutRepo()
  loadBuildUtils()

  def pipeErlangLib
  runStage('load pipeline') {
    env.JENKINS_LIB = "build_utils/jenkins_lib"
    env.SH_TOOLS = "build_utils/sh"
    pipeErlangLib = load("${env.JENKINS_LIB}/pipeErlangLib.groovy")
  }

  pipeErlangLib.runPipe(false, true, 'test')
}

