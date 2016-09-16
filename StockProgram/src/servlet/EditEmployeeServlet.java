package servlet;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import beans.Employee;
import utils.ManagerUtils;
import utils.MyUtils;

@WebServlet(urlPatterns = { "/editEmployee"})
public class EditEmployeeServlet extends HttpServlet{
	private static final long serialVersionUID = 1L;
	
	public EditEmployeeServlet(){
		super();
	}
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
		throws ServletException, IOException{
	
		// connect to the database
		Connection conn = MyUtils.getStoredConnection(request);
		
		//find the employee with this id
		String s= (String)request.getParameter("id");
		
		System.out.println("Value =" +  s);
		int id = Integer.parseInt(s);
		
		Employee employee = null;
		String errorString = null;
		try{
			employee = ManagerUtils.findEmployee(conn, id);
		}catch(SQLException e){
			e.printStackTrace();
			errorString=e.getMessage();
		}
		//Check if there was an error
		// or if the Employee does not exist
		// Redirect to employeeList page if that happens
		if(errorString!=null && employee == null){
			response.sendRedirect(request.getServletPath() + "/employeeList");
			return;
		}
		
		// Store errorString in request attribute, before forward to views.
		request.setAttribute("errorString", errorString);
		request.setAttribute("employee", employee);

		RequestDispatcher dispatcher = request.getServletContext().getRequestDispatcher("/WEB-INF/views/editEmployeeView.jsp");
		dispatcher.forward(request, response);
	}
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException{
		doGet(request, response);
	}
	
}


