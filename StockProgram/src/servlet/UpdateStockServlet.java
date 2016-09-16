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

import beans.Stock;
import utils.ManagerUtils;
import utils.MyUtils;

@WebServlet(urlPatterns = {"/updateStockPrice"})
public class UpdateStockServlet extends HttpServlet{
	private static final long serialVersionUID = 1L;
	public UpdateStockServlet(){
		super();
	}
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
		throws ServletException, IOException{
		//Connect to the database
		Connection conn = MyUtils.getStoredConnection(request);
		
		//Find the Stock with the given symbol
		String stockSymbol = request.getParameter("stockSymbol");
		
		Stock stock = null;
		String errorString = null;
		
		try{
			stock = ManagerUtils.findStock(conn, stockSymbol);	
		}catch(SQLException e){
			e.printStackTrace();
			errorString=e.getMessage();
		}
		//Check if there's an error, 
		// or if the Stock exists
		
		if(errorString!=null && stock==null){
			response.sendRedirect(request.getServletPath() + "/stockList");
			return;
		}
		//Store errorString in request
		request.setAttribute("errorString", errorString);
		request.setAttribute("stock", stock);
		
		RequestDispatcher dispatcher = request.getServletContext().getRequestDispatcher("/WEB-INF/views/updateStockPriceView.jsp");
		dispatcher.forward(request, response);	
	}
	
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException{
		doGet(request, response);
	}
}
