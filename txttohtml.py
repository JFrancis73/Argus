import subprocess
def create_html_table_from_txt(filename, output_file):
  """
  Reads search results and URLs from a text file and creates an HTML table.

  Args:
      filename: Path to the text file containing search results and URLs.
      output_file: Path to the output HTML file.
  """
  with open(filename, 'r') as f:
    data = [line.strip().split(':', 1) for line in f]

  # Create HTML content
  html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Search Results</title>
<style>
  table {
    border-collapse: collapse;
    width: 100%;
  }
  th, td {
    padding: 8px;
    text-align: left;
    border-bottom: 1px solid #ddd;
  }
  th {
    background-color: #f1f1f1;
  }
</style>
</head>
<body>
  <h1>Search Results</h1>
  <table>
    <tr>
      <th>Search Result</th>
      <th>URL</th>
    </tr>
  """

  # Add data to table rows
  for result,url in data:
    html_content += f"""
    <tr>
      <td>{result}</td>
      <td><a href="{url}">{url}</a></td>
    </tr>
    """

  # Close table and HTML tags
  html_content += """
  </table>
</body>
</html>
  """

  # Write HTML content to the output file
  with open(output_file, 'w') as f:
    f.write(html_content)

# Example usage
#create_html_table_from_txt('search_results.txt', 'search_results.html')
#print("HTML file created successfully!")
