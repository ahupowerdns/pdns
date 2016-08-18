#include "dnsname.hh"
/* Quest in life: serve as a rapid block list. If you add a DNSName to a root SuffixMatchNode, 
   anything part of that domain will return 'true' in check */
template<typename T>
struct SuffixMatchTree
{
  SuffixMatchTree(const std::string& name_="", bool endNode_=false) : name(name_), endNode(endNode_)
  {}

  SuffixMatchTree(const SuffixMatchTree& rhs)
  {
    name = rhs.name;
    d_human = rhs.d_human;
    children = rhs.children;
    endNode = rhs.endNode;
    d_value = rhs.d_value;
  }
  std::string name;
  std::string d_human;
  mutable std::set<SuffixMatchTree> children;
  mutable bool endNode;
  mutable T d_value;
  bool operator<(const SuffixMatchTree& rhs) const
  {
    return strcasecmp(name.c_str(), rhs.name.c_str()) < 0;
  }
  typedef SuffixMatchTree value_type;

  template<typename V>
  void visit(const V& v) const {
    for(const auto& c : children) 
      c.visit(v);
    if(endNode)
      v(*this);
  }

  void add(const DNSName& name, const T& t) 
  {
    add(name.getRawLabels(), t);
  }

  void add(std::vector<std::string> labels, const T& value) const
  {
    for(const auto& l : labels) {
      cout<<"'"<<l<<"' ";
    }
    cout<<" -> "<<value<<endl;
    if(labels.empty()) { // this allows insertion of the root
      cout<<"Empty node done"<<endl;
      endNode=true;
      d_value=value;
    }
    else if(labels.size()==1) {
      cout<<"Single node done"<<endl;
      SuffixMatchTree newChild(*labels.begin(), true);
      newChild.d_value=value;
      children.insert(newChild);
    }
    else {
      cout<<"Multiple node, continue"<<endl;
      SuffixMatchTree newnode(*labels.rbegin(), false);
      auto res=children.insert(newnode);
      if(!res.second) {
        children.erase(newnode);
        res=children.insert(newnode);
      }
      labels.pop_back();
      res.first->add(labels, value);
    }
  }

  T* lookup(const DNSName& name, int* matchlen=0)  const
  {
    if(children.empty()) { // speed up empty set
      if(endNode)
        return &d_value;
      return 0;
    }
    return lookup(name.getRawLabels(), matchlen);
  }

  T* lookup(std::vector<std::string> labels, int* matchlen=0) const
  {
    if(labels.empty()) { // optimization
      cout<<"Empty node, "<<endNode<<", value: "<<d_value<<endl;
      if(endNode)
        return &d_value;
      return 0;
    }

    SuffixMatchTree smn(*labels.rbegin());
    auto child = children.find(smn);
    if(child == children.end()) {
      cout<<"Found no child for "<<*labels.rbegin()<<", current node is best we have"<<endl;
      if(endNode) {
        return &d_value;
      }
      return 0;
    }
    cout<<"Found child, increasing matchlen"<<endl;
    if(matchlen)
      *matchlen += labels.rbegin()->size()+1;
    labels.pop_back();
    
    return child->lookup(labels, matchlen);
  }
  
};

