package servlet;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import beans.Portfolio;
import utils.CustomerUtils;
import utils.MyUtils;

@WebServlet(urlPatterns = { "/stockHolding"})
public class StockHoldingServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	public StockHoldingServlet(){
		super();
	}
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException{
		Connection conn = MyUtils.getStoredConnection(request);
		int id = Integer.parseInt(request.getParameter("id"));
		String errorString = null;
		List<Portfolio> list = null;
		try{
			list = CustomerUtils.getStockPortfolio(conn, id);
		}catch(SQLException e){
		e.printStackTrace();
			errorString = e.getMessage();
		}
		
		
		// store the information before forwarding
		
		request.setAttribute("errorString", errorString);
		request.setAttribute("stockPortfolio", list);
		
		//Forward to employeeListView.jsp
		RequestDispatcher dispatcher = request.getServletContext().getRequestDispatcher("/WEB-INF/views/stockHoldingView.jsp");
		dispatcher.forward(request, response);
	}
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException{
		doGet(request, response);
	}
}
